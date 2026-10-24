//! Expiration parsing for upstream and legacy admin transports.
//!
//! v0.29.5 uses prometheus/common v0.68.1's model.ParseDuration, not Go's
//! time.ParseDuration. Components are nonnegative integers in descending unit
//! order, from years through milliseconds; fractions and repeated units fail.

use chrono::Utc;
use headscale_api_acl::go_strconv::quote;

use super::AdminError;

/// Parse Go `time.ParseDuration` syntax into its signed nanosecond value.
/// This is deliberately separate from Prometheus key-expiration durations.
pub fn parse_go_duration_nanos(value: &str) -> Result<i64, String> {
    headscale_api_acl::go_duration::parse_nanos(value)
}

/// Parse the pinned Prometheus duration grammar into signed Go nanoseconds.
pub fn parse_expiration_nanos(value: &str) -> Result<i64, String> {
    if value == "0" {
        return Ok(0);
    }
    if value.is_empty() {
        return Err("empty duration string".into());
    }
    let invalid = || format!("not a valid duration string: {}", quote(value));
    let mut rest = value;
    let mut total = 0u64;
    let mut previous = 0;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return Err(invalid());
        }
        let magnitude = rest[..digits].parse::<u64>().map_err(|_| invalid())?;
        rest = &rest[digits..];
        // ASCII digits cannot occur inside a UTF-8 continuation byte, so both
        // slice boundaries are valid even for malformed/non-ASCII unit names.
        let unit_end = rest
            .bytes()
            .position(|byte| byte.is_ascii_digit())
            .unwrap_or(rest.len());
        if unit_end == 0 {
            return Err(invalid());
        }
        let unit = &rest[..unit_end];
        rest = &rest[unit_end..];
        let (position, multiplier) = match unit {
            "y" => (1, 365 * 24 * 60 * 60 * 1_000_000_000u64),
            "w" => (2, 7 * 24 * 60 * 60 * 1_000_000_000u64),
            "d" => (3, 24 * 60 * 60 * 1_000_000_000u64),
            "h" => (4, 60 * 60 * 1_000_000_000u64),
            "m" => (5, 60 * 1_000_000_000u64),
            "s" => (6, 1_000_000_000u64),
            "ms" => (7, 1_000_000u64),
            _ => {
                return Err(format!(
                    "unknown unit {} in duration {}",
                    quote(unit),
                    quote(value)
                ));
            }
        };
        if position <= previous {
            return Err(invalid());
        }
        previous = position;
        total = magnitude
            .checked_mul(multiplier)
            .and_then(|component| total.checked_add(component))
            .filter(|total| i64::try_from(*total).is_ok())
            .ok_or_else(|| "duration out of range".to_string())?;
    }
    i64::try_from(total).map_err(|_| "duration out of range".into())
}

/// Match expirationFromFlag: even a zero duration produces a timestamp now.
pub(super) fn expiration_from_flag(value: &str) -> Result<prost_types::Timestamp, AdminError> {
    let nanos = parse_expiration_nanos(value)
        .map_err(|error| AdminError::Usage(format!("parsing duration: {error}")))?;
    let expiry = Utc::now() + chrono::Duration::nanoseconds(nanos);
    Ok(prost_types::Timestamp {
        seconds: expiry.timestamp(),
        nanos: expiry.timestamp_subsec_nanos() as i32,
    })
}

/// Parse a duration of the form `<integer><unit>`.
///
/// Supported units: `s` (seconds), `m` (minutes), `h` (hours),
/// `d` (days). Any other suffix, or a missing unit, is rejected. The
/// magnitude must fit in `u64` after multiplication.
///
/// `90d` ⇒ `Ok(90 * 86_400)` = 7_776_000.
pub fn parse_duration_secs(s: &str) -> Result<u64, String> {
    if s.is_empty() {
        return Err("duration cannot be empty".into());
    }
    // Last char is the unit; everything before is the magnitude.
    let boundary = s.char_indices().last().map_or(0, |(index, _)| index);
    let (num_part, unit) = s.split_at(boundary);
    let mult: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        other => {
            return Err(format!(
                "invalid duration unit '{other}'; expected one of s/m/h/d"
            ));
        }
    };
    let n: u64 = num_part
        .parse()
        .map_err(|e| format!("invalid duration magnitude '{num_part}': {e}"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("duration '{s}' overflows u64 seconds"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds() {
        assert_eq!(parse_duration_secs("30s").unwrap(), 30);
    }

    #[test]
    fn minutes() {
        assert_eq!(parse_duration_secs("5m").unwrap(), 300);
    }

    #[test]
    fn hours() {
        assert_eq!(parse_duration_secs("2h").unwrap(), 7_200);
    }

    #[test]
    fn days() {
        assert_eq!(parse_duration_secs("7d").unwrap(), 604_800);
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_duration_secs("").is_err());
    }

    #[test]
    fn rejects_no_unit() {
        assert!(parse_duration_secs("60").is_err());
    }

    #[test]
    fn rejects_bad_unit() {
        assert!(parse_duration_secs("10y").is_err());
    }

    #[test]
    fn rejects_garbage_magnitude() {
        assert!(parse_duration_secs("abc d").is_err());
    }

    #[test]
    fn rejects_overflow() {
        // 18446744073709551615 / 86400 is around 2.1e14, so this
        // overflows on multiply.
        let huge = format!("{}d", u64::MAX);
        assert!(parse_duration_secs(&huge).is_err());
    }
}
